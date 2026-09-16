rule libavcodec_dca_lossy_quant_d__flt64___64_big_256_ {
  strings:
    $a0 = { 00 00 00 00 00 00 00 00 3f f9 99 99 99 99 99 9a 3f f0 00 00 00 00 00 00 3f e9 99 99 99 99 99 9a 3f e2 e1 47 ae 14 7a e1 3f e0 00 00 00 00 00 00 3f da e1 47 ae 14 7a e1 3f d5 c2 8f 5c 28 f5 c3 3f c8 51 eb 85 1e b8 52 3f bc 28 f5 c2 8f 5c 29 3f ae b8 51 eb 85 1e b8 3f a1 eb 85 1e b8 51 ec 3f 93 74 bc 6a 7e f9 db 3f 86 87 2b 02 0c 49 ba 3f 7a 9f be 76 c8 b4 39 3f 70 62 4d d2 f1 a9 fc 3f 64 7a e1 47 ae 14 7b 3f 56 f0 06 8d b8 ba c7 3f 4a 36 e2 eb 1c 43 2d 3f 3d 7d bf 48 7f cb 92 3f 33 a9 2a 30 55 32 61 3f 26 48 40 e1 71 9f 80 3f 14 f8 b5 88 e3 68 f1 3f 04 f8 b5 88 e3 68 f1 3e f4 f8 b5 88 e3 68 f1 3e e4 f8 b5 88 e3 68 f1 3e d4 f8 b5 88 e3 68 f1 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

  condition:
    $a0
}