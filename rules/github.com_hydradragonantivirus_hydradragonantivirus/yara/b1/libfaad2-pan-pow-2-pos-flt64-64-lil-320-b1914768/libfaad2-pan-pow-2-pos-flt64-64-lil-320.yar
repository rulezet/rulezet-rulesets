rule libfaad2_pan_pow_2_pos__flt64___64_lil_320_ {
  strings:
    $a0 = { 00 00 00 00 00 00 f0 3f 00 00 00 00 00 00 f0 3f 00 00 00 00 00 00 f0 3f 00 00 00 00 00 00 f0 3f 00 00 00 00 00 00 f0 3f 72 b1 58 79 b8 f3 f1 3f 72 b1 58 79 b8 f3 f1 3f e3 9f be 0a 95 24 f4 3f e3 9f be 0a 95 24 f4 3f e3 9f be 0a 95 24 f4 3f e3 9f be 0a 95 24 f4 3f e3 9f be 0a 95 24 f4 3f 51 2d 22 8a c9 5b f9 3f a5 ca e6 60 ec 73 fc 3f a5 ca e6 60 ec 73 fc 3f 56 6e 58 09 cc 99 f6 3f 51 2d 22 8a c9 5b f9 3f 7e 79 b7 68 b7 ec ff 3f 5a 4f 08 78 2d 8c 06 40 1d 58 8e 90 81 4c 09 40 51 2d 22 8a c9 5b f9 3f 19 6c 8f 83 b7 ec ff 3f 5a 4f 08 78 2d 8c 06 40 41 77 93 29 30 de 11 40 70 0f 9d f9 30 7e 16 40 a5 ca e6 60 ec 73 fc 3f 96 07 e9 29 72 18 04 40 41 77 93 29 30 de 11 40 b3 fc 0a e3 b8 c5 1f 40 e8 a1 b6 0d a3 70 26 40 7e 79 b7 68 b7 ec ff 3f b8 2c 15 0a c7 62 0c 40 55 98 08 65 2b 51 1c 40 a5 86 36 00 1b 40 2c 40 80 47 54 a8 6e 1e 39 40 96 07 e9 29 72 18 04 40 9d 7a 49 08 fb 0b 14 40 e8 a1 b6 0d a3 70 26 40 80 47 54 a8 6e 1e 39 40 a0 fd 48 11 19 1e 4c 40 }

  condition:
    $a0
}