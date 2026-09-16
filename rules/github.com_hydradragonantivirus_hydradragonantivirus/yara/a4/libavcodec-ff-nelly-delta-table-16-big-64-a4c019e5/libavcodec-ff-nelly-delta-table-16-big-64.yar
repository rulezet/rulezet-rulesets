rule libavcodec_ff_nelly_delta_table__16_big_64_ {
  strings:
    $a0 = { D2 33 DB 34 E1 1A E5 6F E8 C4 EB 8F EE 09 F0 39 F2 4D F4 2A F5 DC F7 86 F9 12 FA 99 FC 08 FD 6C FE B7 FF FF 01 51 02 B8 04 3D 05 E8 07 AA 09 81 0B 98 0D F1 10 DA 14 9F 19 DE 1F DA 27 5C 32 AF }

  condition:
    $a0
}