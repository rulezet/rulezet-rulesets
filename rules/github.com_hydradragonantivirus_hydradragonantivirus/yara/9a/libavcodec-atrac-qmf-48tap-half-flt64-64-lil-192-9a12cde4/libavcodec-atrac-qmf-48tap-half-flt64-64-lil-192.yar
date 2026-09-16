rule libavcodec_atrac_qmf_48tap_half__flt64___64_lil_192_ {
  strings:
    $a0 = { a3 01 79 ae 8d a8 ee be d5 6a fd 3f b1 21 18 bf 6a 37 d3 60 57 71 0d bf b8 a2 9f da d6 bc 33 3f 6e 39 cd f9 9f c0 2f 3f 33 2e a6 7d f8 f2 4b bf a2 c7 1c 81 c0 0e 41 bf 95 92 14 82 a4 a9 60 3f 7c 66 04 80 1f ab 49 3f bb 76 e7 1d 27 44 71 bf f6 61 b3 80 0b c7 48 bf 7e e5 4f 80 92 0e 80 3f de 5e 09 42 0b 09 10 bf e7 2b 71 b2 47 87 8b bf fb e7 8e 62 9e 2c 64 3f fc 7e 97 3d fc 41 96 3f 34 53 c9 1c a5 f4 7f bf 3b e8 9d 00 46 74 a1 bf 45 25 9e 81 cb 42 93 3f c7 53 f4 5f 9e d0 ab 3f dd db 0e bc 43 52 a6 bf 4a a8 ff fd 40 71 b9 bf 52 89 04 b6 f7 e7 c0 3f fa 8d 9f 5b 22 b6 dd 3f }

  condition:
    $a0
}