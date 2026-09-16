rule TTP_XOR_QUAD_CurrentVersionRun_62e2 {
  strings:
    $key_62e2 = { 31 8d [2] 15 83 [2] 3e af [2] 10 8d [2] 04 96 [2] 0b 8c [2] 15 91 [2] 17 90 [2] 0c 96 [2] 10 91 [2] 0c be }

  condition:
    any of them
}