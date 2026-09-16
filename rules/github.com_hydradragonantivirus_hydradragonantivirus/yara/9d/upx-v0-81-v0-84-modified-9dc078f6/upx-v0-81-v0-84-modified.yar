import "pe"
rule UPX_v0_81___v0_84_Modified {
  strings:
    $a0 = { 01 DB ?? 07 8B 1E 83 EE FC 11 DB ?? ED B8 01 00 00 00 01 DB ?? 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 77 EF }

  condition:
    $a0 at pe.entry_point
}