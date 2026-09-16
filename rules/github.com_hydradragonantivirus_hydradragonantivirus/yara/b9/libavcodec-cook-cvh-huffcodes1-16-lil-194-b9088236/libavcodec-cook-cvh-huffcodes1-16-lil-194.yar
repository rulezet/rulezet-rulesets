rule libavcodec_COOK_cvh_huffcodes1__16_lil_194_ {
  strings:
    $a0 = { 00 00 08 00 14 00 30 00 6a 00 e2 00 e3 00 e4 01 ec 03 ed 03 09 00 15 00 31 00 6b 00 6c 00 e4 00 e5 00 e5 01 e6 01 f0 07 16 00 17 00 32 00 6d 00 e6 00 e7 00 e7 01 e8 01 ee 03 f1 07 33 00 34 00 6e 00 e8 00 e9 00 e9 01 ea 01 ef 03 f2 07 f6 0f 6f 00 70 00 ea 00 eb 00 eb 01 ec 01 f0 03 f3 07 f4 07 fa 1f ec 00 ed 00 ee 00 ed 01 ee 01 f1 03 f2 03 f5 07 f7 0f fa 3f ef 00 f0 00 f1 00 ef 01 f3 03 f6 07 f7 07 f8 0f fb 1f fe 7f f0 01 f1 01 f2 01 f4 03 f8 07 f9 0f fa 0f fb 3f fc 3f 00 00 f3 01 f4 01 f5 01 f5 03 f9 07 fb 0f fd 3f fe ff 00 00 00 00 f6 03 f7 03 fa 07 fc 0f fc 1f fe 3f ff ff }

  condition:
    $a0
}