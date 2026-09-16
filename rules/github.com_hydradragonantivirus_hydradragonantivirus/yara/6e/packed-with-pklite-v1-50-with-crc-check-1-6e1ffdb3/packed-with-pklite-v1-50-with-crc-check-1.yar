import "pe"
rule Packed_with__PKLITE_v1_50_with_CRC_check__1_ {
  strings:
    $a0 = { 1F B4 09 BA ?? ?? CD 21 B8 ?? ?? CD 21 }

  condition:
    $a0 at pe.entry_point
}