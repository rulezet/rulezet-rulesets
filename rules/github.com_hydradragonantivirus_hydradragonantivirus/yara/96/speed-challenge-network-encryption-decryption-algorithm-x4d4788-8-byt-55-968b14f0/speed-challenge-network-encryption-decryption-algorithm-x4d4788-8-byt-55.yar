rule Speed_Challenge_network_encryption_decryption_algorithm_X4d4788__8_byt_55_ {
  strings:
    $a0 = { 53 7c c9 16 6c b3 8a e1 1e a7 02 6f de e0 0d c6 50 2d 13 b5 37 0a 42 0a 48 90 f6 b2 2a d2 07 23 3b a3 05 ef 09 d5 6d 53 33 92 da 31 fc a0 b0 53 29 46 8c 5b f3 21 23 }

  condition:
    $a0
}