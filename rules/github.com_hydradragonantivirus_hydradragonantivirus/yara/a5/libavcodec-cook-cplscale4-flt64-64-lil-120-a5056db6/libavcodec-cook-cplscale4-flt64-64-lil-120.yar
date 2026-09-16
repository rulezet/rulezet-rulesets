rule libavcodec_COOK_cplscale4__flt64___64_lil_120_ {
  strings:
    $a0 = { 02 00 00 60 42 ba ef 3f fe ff ff 1f db 24 ef 3f fd ff ff 1f 25 7f ee 3f fe ff ff 5f a7 c3 ed 3f ff ff ff bf 16 e9 ec 3f 03 00 00 20 27 dd eb 3f 03 00 00 00 12 70 ea 3f fc ff ff 5f 9e a0 e6 3f 04 00 00 20 6b 07 e2 3f fd ff ff 9f 8c 78 df 3f 06 00 00 00 9a 6f db 3f 00 00 00 80 8e 80 d7 3f f9 ff ff 7f cd 62 d3 3f 10 00 00 00 8b 68 cd 3f 01 00 00 00 a7 aa c0 3f }

  condition:
    $a0
}