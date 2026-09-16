rule Speed_Challenge_network_encryption_decryption_algorithm_X4d46f4__8_byt_43_ {
  strings:
    $a0 = { 74 d0 d7 3b c5 2d fa b2 19 fc 4a 77 fb e8 53 20 35 1d ab 73 99 9f 61 2e 58 25 15 1c 10 00 62 72 9a 46 ca 45 64 e3 c5 a0 59 ce a4 }

  condition:
    $a0
}