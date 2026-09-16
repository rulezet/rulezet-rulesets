rule TTP_XOR_QUAD_CurrentVersionRun_382a {
  strings:
    $key_382a = { 6b 45 [2] 4f 4b [2] 64 67 [2] 4a 45 [2] 5e 5e [2] 51 44 [2] 4f 59 [2] 4d 58 [2] 56 5e [2] 4a 59 [2] 56 76 }

  condition:
    any of them
}