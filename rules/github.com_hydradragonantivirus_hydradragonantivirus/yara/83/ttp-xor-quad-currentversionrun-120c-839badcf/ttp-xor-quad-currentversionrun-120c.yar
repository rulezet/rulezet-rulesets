rule TTP_XOR_QUAD_CurrentVersionRun_120c {
  strings:
    $key_120c = { 41 63 [2] 65 6d [2] 4e 41 [2] 60 63 [2] 74 78 [2] 7b 62 [2] 65 7f [2] 67 7e [2] 7c 78 [2] 60 7f [2] 7c 50 }

  condition:
    any of them
}