rule libavcodec_asus_v1_v2_ccp_tab__8_byt_34_ {
  strings:
    $a0 = { 02 02 07 05 0b 05 03 05 0d 05 05 05 09 05 01 05 0e 05 06 05 0a 05 02 05 0c 05 04 05 08 05 03 02 0f 05 }

  condition:
    $a0
}