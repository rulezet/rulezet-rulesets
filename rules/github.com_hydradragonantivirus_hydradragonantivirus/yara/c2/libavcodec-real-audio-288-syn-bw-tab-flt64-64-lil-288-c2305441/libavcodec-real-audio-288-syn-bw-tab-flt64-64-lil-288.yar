rule libavcodec_real_audio_288_syn_bw_tab__flt64___64_lil_288_ {
  strings:
    $a0 = { 00 00 00 00 00 a0 ef 3f 96 0a f2 ff 1f 41 ef 3f 12 d9 02 a0 5c e3 ee 3f 63 b4 d5 7f b2 86 ee 3f 2c ac cd 5f 1e 2b ee 3f b0 5f c4 ff 9c d0 ed 3f 91 de 1c 20 2b 77 ed 3f a7 3d d4 9f c5 1e ed 3f f4 fc d6 3f 69 c7 ec 3f 02 f8 e1 ff 12 71 ec 3f 68 24 05 c0 bf 1b ec 3f b1 5d fd 7f 6c c7 eb 3f c5 ef 10 40 16 74 eb 3f 30 b6 fc ff b9 21 eb 3f 2e 53 3d e0 54 d0 ea 3f eb 31 06 e0 e3 7f ea 3f f6 4a 0a 40 64 30 ea 3f 2f d0 3c 20 d3 e1 e9 3f 12 83 07 a0 2d 94 e9 3f 25 42 ca 1f 71 47 e9 3f a5 af 01 c0 9a fb e8 3f 57 c9 fa df a7 b0 e8 3f bf 6d 15 e0 95 66 e8 3f 03 0b 28 20 62 1d e8 3f 48 0f 09 00 0a d5 e7 3f 12 59 18 e0 8a 8d e7 3f 7a 3c d9 3f e2 46 e7 3f 58 ee e1 9f 0d 01 e7 3f 24 33 3f 80 0a bc e6 3f 98 ee ea 5f d6 77 e6 3f 3e 1c 3b e0 6e 34 e6 3f c4 85 d6 9f d1 f1 e5 3f 61 d0 dc 1f fc af e5 3f d5 fc 3d 20 ec 6e e5 3f 20 2b d7 5f 9f 2e e5 3f cc 56 fe 7f 13 ef e4 3f }

  condition:
    $a0
}