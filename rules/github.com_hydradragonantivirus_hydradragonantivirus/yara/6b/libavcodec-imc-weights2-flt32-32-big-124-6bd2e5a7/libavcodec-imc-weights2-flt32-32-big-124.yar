rule libavcodec_imc_weights2__flt32___32_big_124_ {
  strings:
    $a0 = { 3b 53 fc 97 3b 65 4d 21 3b 82 8d 4e 3b 01 d6 59 3a 98 a7 2b 3a ea fd 64 3a b7 fd 07 3a ae af 55 3a c5 4b 23 3a ff ac 9e 3b 35 d8 14 3b 87 e5 a8 3b cd b4 53 3c 19 6b 81 3c 8c 68 8e 3c b7 8b 1c 3c e8 a1 09 3d 28 a0 b8 3d 41 ce f2 3d 59 c1 8d 3d 88 85 c6 3d a4 02 3e 3d aa 4f 29 3d b0 6a 03 3d ca 98 17 3d e5 c7 8a 3d eb fc 22 3d f4 f7 a9 3e 0b 71 32 3e 1e 28 24 3e 26 96 e6 }

  condition:
    $a0
}