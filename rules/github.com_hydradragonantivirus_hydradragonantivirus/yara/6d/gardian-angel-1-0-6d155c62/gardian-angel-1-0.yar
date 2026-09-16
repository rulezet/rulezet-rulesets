import "pe"
rule Gardian_Angel_1_0 {
  strings:
    $a0 = { 06 8C C8 8E D8 8E C0 FC BF ?? ?? EB }

  condition:
    $a0 at pe.entry_point
}