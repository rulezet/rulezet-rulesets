rule TTP_XOR_QUAD_CurrentVersionRun_092a {
  strings:
    $key_092a = { 5a 45 [2] 7e 4b [2] 55 67 [2] 7b 45 [2] 6f 5e [2] 60 44 [2] 7e 59 [2] 7c 58 [2] 67 5e [2] 7b 59 [2] 67 76 }

  condition:
    any of them
}