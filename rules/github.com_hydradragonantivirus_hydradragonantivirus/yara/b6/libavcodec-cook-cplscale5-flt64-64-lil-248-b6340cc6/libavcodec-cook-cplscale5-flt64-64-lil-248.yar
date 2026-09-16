rule libavcodec_COOK_cplscale5__flt64___64_lil_248_ {
  strings:
    $a0 = { 03 00 00 00 a1 de ef 3f 03 00 00 80 be 99 ef 3f 04 00 00 20 ba 51 ef 3f fe ff ff df 30 06 ef 3f 02 00 00 e0 a9 b6 ee 3f fd ff ff 5f 8f 62 ee 3f 02 00 00 e0 24 09 ee 3f 00 00 00 00 76 a9 ed 3f 04 00 00 00 3e 42 ed 3f ff ff ff 1f bd d1 ec 3f 00 00 00 e0 6a 55 ec 3f 02 00 00 e0 5f c9 eb 3f 04 00 00 40 00 27 eb 3f 03 00 00 e0 55 61 ea 3f fd ff ff ff b2 56 e9 3f fc ff ff 5f 9e a0 e6 3f 00 00 00 a0 28 8b e3 3f 00 00 00 c0 f3 1c e2 3f ff ff ff 9f 06 ef e0 3f f8 ff ff 1f 32 be df 3f 05 00 00 80 ee be dd 3f 03 00 00 a0 30 d1 db 3f 05 00 00 00 cc ea d9 3f 05 00 00 20 97 03 d8 3f 06 00 00 a0 e0 13 d6 3f 04 00 00 20 35 13 d4 3f 07 00 00 60 dd f6 d1 3f ff ff ff 1f 69 5e cf 3f fe ff ff bf fe 42 ca 3f f0 ff ff 1f 40 29 c4 3f 00 00 00 c0 61 15 b7 3f }

  condition:
    $a0
}