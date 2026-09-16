import "pe"
rule DIET_v1_02b__v1_10a__v1_20 {
  strings:
    $a0 = { BE ?? ?? BF ?? ?? B9 ?? ?? 3B FC 72 ?? B4 4C CD 21 FD F3 A5 FC }

  condition:
    $a0 at pe.entry_point
}