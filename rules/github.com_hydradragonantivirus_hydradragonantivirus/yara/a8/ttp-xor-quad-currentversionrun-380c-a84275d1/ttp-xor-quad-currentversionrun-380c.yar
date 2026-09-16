rule TTP_XOR_QUAD_CurrentVersionRun_380c {
  strings:
    $key_380c = { 6b 63 [2] 4f 6d [2] 64 41 [2] 4a 63 [2] 5e 78 [2] 51 62 [2] 4f 7f [2] 4d 7e [2] 56 78 [2] 4a 7f [2] 56 50 }

  condition:
    any of them
}