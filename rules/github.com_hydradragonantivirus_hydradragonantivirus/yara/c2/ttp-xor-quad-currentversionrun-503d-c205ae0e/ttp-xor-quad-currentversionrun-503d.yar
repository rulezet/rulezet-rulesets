rule TTP_XOR_QUAD_CurrentVersionRun_503d {
  strings:
    $key_503d = { 03 52 [2] 27 5c [2] 0c 70 [2] 22 52 [2] 36 49 [2] 39 53 [2] 27 4e [2] 25 4f [2] 3e 49 [2] 22 4e [2] 3e 61 }

  condition:
    any of them
}