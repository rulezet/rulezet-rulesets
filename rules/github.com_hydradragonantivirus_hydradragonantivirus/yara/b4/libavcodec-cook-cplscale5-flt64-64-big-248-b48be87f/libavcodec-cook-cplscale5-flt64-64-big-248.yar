rule libavcodec_COOK_cplscale5__flt64___64_big_248_ {
  strings:
    $a0 = { 3f ef de a1 00 00 00 03 3f ef 99 be 80 00 00 03 3f ef 51 ba 20 00 00 04 3f ef 06 30 df ff ff fe 3f ee b6 a9 e0 00 00 02 3f ee 62 8f 5f ff ff fd 3f ee 09 24 e0 00 00 02 3f ed a9 76 00 00 00 00 3f ed 42 3e 00 00 00 04 3f ec d1 bd 1f ff ff ff 3f ec 55 6a e0 00 00 00 3f eb c9 5f e0 00 00 02 3f eb 27 00 40 00 00 04 3f ea 61 55 e0 00 00 03 3f e9 56 b2 ff ff ff fd 3f e6 a0 9e 5f ff ff fc 3f e3 8b 28 a0 00 00 00 3f e2 1c f3 c0 00 00 00 3f e0 ef 06 9f ff ff ff 3f df be 32 1f ff ff f8 3f dd be ee 80 00 00 05 3f db d1 30 a0 00 00 03 3f d9 ea cc 00 00 00 05 3f d8 03 97 20 00 00 05 3f d6 13 e0 a0 00 00 06 3f d4 13 35 20 00 00 04 3f d1 f6 dd 60 00 00 07 3f cf 5e 69 1f ff ff ff 3f ca 42 fe bf ff ff fe 3f c4 29 40 1f ff ff f0 3f b7 15 61 c0 00 00 00 }

  condition:
    $a0
}