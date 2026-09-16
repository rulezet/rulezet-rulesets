rule Speed_Challenge_network_encryption_decryption_algorithm_X4d468c__8_byt_47_ {
  strings:
    $a0 = { f1 b2 cd 0e 16 a8 5f 2c c7 f2 15 69 17 09 c2 20 a1 82 c3 8f 3b 56 46 54 2f fb 3d d0 58 94 e2 ea 5c cd 80 c7 ef 9e 3b 91 c4 bb bc 3b ae c6 01 }

  condition:
    $a0
}