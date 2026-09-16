rule libavcodec_indeo3_corrector_type_0__8_byt_24_ {
  strings:
    $a0 = { c3 9f 85 73 65 5d 57 4d c3 9f 85 73 65 5d 57 4d 80 4f 4f 4f 4f 4f 4f 4f }

  condition:
    $a0
}