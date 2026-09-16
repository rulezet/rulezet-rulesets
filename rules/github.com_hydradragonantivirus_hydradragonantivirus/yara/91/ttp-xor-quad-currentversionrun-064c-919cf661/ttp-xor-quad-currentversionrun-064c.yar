rule TTP_XOR_QUAD_CurrentVersionRun_064c {
  strings:
    $key_064c = { 55 23 [2] 71 2d [2] 5a 01 [2] 74 23 [2] 60 38 [2] 6f 22 [2] 71 3f [2] 73 3e [2] 68 38 [2] 74 3f [2] 68 10 }

  condition:
    any of them
}