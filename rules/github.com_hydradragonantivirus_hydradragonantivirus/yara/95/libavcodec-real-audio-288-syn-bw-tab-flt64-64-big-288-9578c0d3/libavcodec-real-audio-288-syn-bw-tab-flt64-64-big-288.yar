rule libavcodec_real_audio_288_syn_bw_tab__flt64___64_big_288_ {
  strings:
    $a0 = { 3f ef a0 00 00 00 00 00 3f ef 41 1f ff f2 0a 96 3f ee e3 5c a0 02 d9 12 3f ee 86 b2 7f d5 b4 63 3f ee 2b 1e 5f cd ac 2c 3f ed d0 9c ff c4 5f b0 3f ed 77 2b 20 1c de 91 3f ed 1e c5 9f d4 3d a7 3f ec c7 69 3f d6 fc f4 3f ec 71 12 ff e1 f8 02 3f ec 1b bf c0 05 24 68 3f eb c7 6c 7f fd 5d b1 3f eb 74 16 40 10 ef c5 3f eb 21 b9 ff fc b6 30 3f ea d0 54 e0 3d 53 2e 3f ea 7f e3 e0 06 31 eb 3f ea 30 64 40 0a 4a f6 3f e9 e1 d3 20 3c d0 2f 3f e9 94 2d a0 07 83 12 3f e9 47 71 1f ca 42 25 3f e8 fb 9a c0 01 af a5 3f e8 b0 a7 df fa c9 57 3f e8 66 95 e0 15 6d bf 3f e8 1d 62 20 28 0b 03 3f e7 d5 0a 00 09 0f 48 3f e7 8d 8a e0 18 59 12 3f e7 46 e2 3f d9 3c 7a 3f e7 01 0d 9f e1 ee 58 3f e6 bc 0a 80 3f 33 24 3f e6 77 d6 5f ea ee 98 3f e6 34 6e e0 3b 1c 3e 3f e5 f1 d1 9f d6 85 c4 3f e5 af fc 1f dc d0 61 3f e5 6e ec 20 3d fc d5 3f e5 2e 9f 5f d7 2b 20 3f e4 ef 13 7f fe 56 cc }

  condition:
    $a0
}