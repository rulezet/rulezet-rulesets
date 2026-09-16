rule TTP_XOR_QUAD_CurrentVersionRun_320a {
  strings:
    $key_320a = { 61 65 [2] 45 6b [2] 6e 47 [2] 40 65 [2] 54 7e [2] 5b 64 [2] 45 79 [2] 47 78 [2] 5c 7e [2] 40 79 [2] 5c 56 }

  condition:
    any of them
}