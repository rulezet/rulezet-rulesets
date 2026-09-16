rule GameGuard_files_encryption_public_key__8_byt_84_ {
  strings:
    $a0 = { 06 02 00 00 00 24 00 00 52 53 41 31 00 02 00 00 01 00 01 00 fb e3 fc 09 af ae 65 8c 96 4c c5 37 d2 a4 77 e7 4c 41 c2 cf f2 fe 2d 9c 80 94 0c 88 6d b3 84 9f 8c 22 a0 c9 cd c0 ab 30 65 82 42 3c ee 3c a8 b7 11 d6 22 fa fb 23 f7 72 cd e7 d0 6f 6a 8e 96 e3 }

  condition:
    $a0
}