rule OpenJPEG_dwt_norms__flt64___64_big_296_ {
  strings:
    $a0 = { 3f f0 00 00 00 00 00 00 3f f8 00 00 00 00 00 00 40 06 00 00 00 00 00 00 40 15 80 00 00 00 00 00 40 25 5c 28 f5 c2 8f 5c 40 35 57 0a 3d 70 a3 d7 40 45 55 c2 8f 5c 28 f6 40 55 55 1e b8 51 eb 85 40 65 56 66 66 66 66 66 40 75 54 cc cc cc cc cd 3f f0 9b a5 e3 53 f7 cf 3f f9 78 d4 fd f3 b6 46 40 07 5a 1c ac 08 31 27 40 16 cf df 3b 64 5a 1d 40 26 a8 f5 c2 8f 5c 29 40 36 a3 d7 0a 3d 70 a4 40 46 a0 00 00 00 00 00 40 56 9e b8 51 eb 85 1f 40 66 9c cc cc cc cc cd 3f f0 9b a5 e3 53 f7 cf 3f f9 78 d4 fd f3 b6 46 40 07 5a 1c ac 08 31 27 40 16 cf df 3b 64 5a 1d 40 26 a8 f5 c2 8f 5c 29 40 36 a3 d7 0a 3d 70 a4 40 46 a0 00 00 00 00 00 40 56 9e b8 51 eb 85 1f 40 66 9c cc cc cc cc cd 3f e6 fe c5 6d 5c fa ad 3f ed 7f 62 b6 ae 7d 56 3f f9 60 41 89 37 4b c7 40 08 58 10 62 4d d2 f2 40 18 13 74 bc 6a 7e fa 40 28 05 1e b8 51 eb 85 40 38 00 00 00 00 00 00 40 47 fc 28 f5 c2 8f 5c 40 57 fb 85 1e b8 51 ec }

  condition:
    $a0
}