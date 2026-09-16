import "pe"
rule _Packed_with_PKLITE_v150_with_CRC_check_1_ {
  meta:
    description = "Packed with: PKLITE v1.50 with CRC check (1)"

  strings:
    $0 = { 1F B4 09 BA ?? ?? CD 21 B8 ?? ?? CD 21 }

  condition:
    $0 at pe.entry_point
}