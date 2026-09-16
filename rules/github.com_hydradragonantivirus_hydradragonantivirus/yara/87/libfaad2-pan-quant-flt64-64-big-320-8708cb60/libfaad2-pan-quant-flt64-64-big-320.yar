rule libfaad2_pan_quant__flt64___64_big_320_ {
  strings:
    $a0 = { 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 3f c5 42 c3 c9 ee cb fb 3f c5 42 c3 c9 ee cb fb 3f d5 42 c3 c9 ee cb fb 3f d5 42 c3 c9 ee cb fb 3f d5 42 c3 c9 ee cb fb 3f d5 42 c3 c9 ee cb fb 3f d5 42 c3 c9 ee cb fb 3f e5 42 c3 c9 ee cb fb 3f ea 93 74 bc 6a 7e fa 3f ea 93 74 bc 6a 7e fa 3f df e4 25 ae e6 31 f9 3f e5 42 c3 c9 ee cb fb 3f ef e4 25 ae e6 31 f9 3f f7 eb 1c 43 2c a5 7a 3f fa 93 74 bc 6a 7e fa 3f e5 42 c3 c9 ee cb fb 3f ef e4 25 ae e6 31 f9 3f f7 eb 1c 43 2c a5 7a 40 01 46 3f 14 12 05 bc 40 03 ee 63 1f 8a 09 03 3f ea 93 74 bc 6a 7e fa 3f f5 42 c3 c9 ee cb fb 40 01 46 3f 14 12 05 bc 40 07 ea e7 d5 66 cf 42 40 0b e7 6c 8b 43 95 81 3f ef e4 25 ae e6 31 f9 3f fd 3b cd 35 a8 58 79 40 06 96 bb 98 c7 e2 82 40 0e 8f c5 04 81 6f 00 40 12 9a 51 19 ce 07 5f 3f f5 42 c3 c9 ee cb fb 40 02 9a 36 e2 eb 1c 43 40 0b e7 6c 8b 43 95 81 40 12 9a 51 19 ce 07 5f 40 17 40 eb ed fa 43 fe }

  condition:
    $a0
}