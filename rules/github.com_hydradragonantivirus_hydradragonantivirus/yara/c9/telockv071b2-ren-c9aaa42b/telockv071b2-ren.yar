import "pe"
rule tElockv071b2_ren: tE {
  meta:
    author = "_pusher_"
    date   = "2015-11"

  strings:
    $a0 = { 60 E8 44 11 ?? ?? C3 83 }

  condition:
    $a0 at pe.entry_point
}