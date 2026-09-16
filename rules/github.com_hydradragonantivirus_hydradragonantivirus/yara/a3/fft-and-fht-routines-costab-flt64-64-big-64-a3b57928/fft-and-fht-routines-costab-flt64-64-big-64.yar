rule FFT_and_FHT_routines_costab__flt64___64_big_64_ {
  strings:
    $a0 = { 3f ed 90 6b cf 32 8d 46 3f d8 7d e2 a6 ae a9 63 3f ef d8 8d a3 d1 25 26 3f b9 17 a6 bc 29 b4 2c 3f ef fd 88 60 84 cd 0d 3f 99 21 55 f7 a3 66 7f 3f ef ff d8 85 8e 8a 92 3f 79 21 f0 fe 67 00 71 }

  condition:
    $a0
}