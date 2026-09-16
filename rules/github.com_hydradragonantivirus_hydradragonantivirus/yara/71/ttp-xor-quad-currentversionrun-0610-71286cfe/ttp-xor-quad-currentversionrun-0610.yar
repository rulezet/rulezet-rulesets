rule TTP_XOR_QUAD_CurrentVersionRun_0610 {
  strings:
    $key_0610 = { 55 7f [2] 71 71 [2] 5a 5d [2] 74 7f [2] 60 64 [2] 6f 7e [2] 71 63 [2] 73 62 [2] 68 64 [2] 74 63 [2] 68 4c }

  condition:
    any of them
}