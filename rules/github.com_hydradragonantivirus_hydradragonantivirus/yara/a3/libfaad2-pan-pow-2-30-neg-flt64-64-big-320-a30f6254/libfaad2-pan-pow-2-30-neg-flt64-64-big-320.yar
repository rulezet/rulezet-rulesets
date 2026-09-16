rule libfaad2_pan_pow_2_30_neg__flt64___64_big_320_ {
  strings:
    $a0 = { 3f f0 00 00 00 00 00 00 3f f0 00 00 00 00 00 00 3f f0 00 00 00 00 00 00 3f f0 00 00 00 00 00 00 3f f0 00 00 00 00 00 00 3f ef e0 9f 21 c3 ca 1a 3f ef e0 9f 21 c3 ca 1a 3f ef c1 5d 07 f6 77 1e 3f ef c1 5d 07 f6 77 1e 3f ef c1 5d 07 6d 06 bf 3f ef c1 5d 07 f6 77 1e 3f ef c1 5d 07 f6 77 1e 3f ef 83 34 ab 02 77 aa 3f ef 64 4e 2b 31 31 25 3f ef 64 4e 2b 31 31 25 3f ef a2 39 95 10 e2 95 3f ef 83 34 ab 02 77 aa 3f ef 45 85 f8 9f 5a f1 3f ee e9 e2 04 d3 8a 92 3f ee cb 91 dd 48 d7 1b 3f ef 83 34 ab 02 77 aa 3f ef 45 85 f8 9f 5a f1 3f ee e9 e2 04 d3 8a 92 3f ee 71 53 4b 45 67 82 3f ee 35 c1 43 09 72 a3 3f ef 64 4e 2b 31 31 25 3f ef 08 50 02 f7 ac 1f 3f ee 71 53 4b 45 67 82 3f ed dd 39 b8 43 b9 fa 3f ed 85 b5 9b a5 2e f0 3f ef 45 85 f8 9f 5a f1 3f ee ad 5f 6f 59 dd a0 3f ed fa 9f 42 72 62 c0 3f ed 4b ec 32 76 52 75 3f ec bd 61 a3 9a 34 b0 3f ef 08 50 02 f7 ac 1f 3f ee 53 7d f2 5a 61 31 3f ed 85 b5 9b a5 2e f0 3f ec bd 61 a3 9a 34 b0 3f eb fa 5d 06 73 eb 12 }

  condition:
    $a0
}