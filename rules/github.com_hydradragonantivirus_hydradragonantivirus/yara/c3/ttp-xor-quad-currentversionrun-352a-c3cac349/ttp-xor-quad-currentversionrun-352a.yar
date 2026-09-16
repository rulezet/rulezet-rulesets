rule TTP_XOR_QUAD_CurrentVersionRun_352a {
  strings:
    $key_352a = { 66 45 [2] 42 4b [2] 69 67 [2] 47 45 [2] 53 5e [2] 5c 44 [2] 42 59 [2] 40 58 [2] 5b 5e [2] 47 59 [2] 5b 76 }

  condition:
    any of them
}