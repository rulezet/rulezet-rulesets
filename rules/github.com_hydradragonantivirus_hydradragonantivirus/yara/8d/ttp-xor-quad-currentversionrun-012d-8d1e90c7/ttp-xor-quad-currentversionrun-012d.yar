rule TTP_XOR_QUAD_CurrentVersionRun_012d {
  strings:
    $key_012d = { 52 42 [2] 76 4c [2] 5d 60 [2] 73 42 [2] 67 59 [2] 68 43 [2] 76 5e [2] 74 5f [2] 6f 59 [2] 73 5e [2] 6f 71 }

  condition:
    any of them
}