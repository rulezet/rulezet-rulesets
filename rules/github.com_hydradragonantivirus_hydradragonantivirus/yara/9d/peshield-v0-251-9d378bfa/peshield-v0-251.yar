import "pe"
rule PESHiELD_v0_251 {
  strings:
    $a0 = { 5D 83 ED 06 EB 02 EA 04 8D }

  condition:
    $a0 at pe.entry_point
}