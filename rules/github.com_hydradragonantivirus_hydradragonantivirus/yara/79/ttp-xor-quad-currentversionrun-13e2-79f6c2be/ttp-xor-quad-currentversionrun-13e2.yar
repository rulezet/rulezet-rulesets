rule TTP_XOR_QUAD_CurrentVersionRun_13e2 {
  strings:
    $key_13e2 = { 40 8d [2] 64 83 [2] 4f af [2] 61 8d [2] 75 96 [2] 7a 8c [2] 64 91 [2] 66 90 [2] 7d 96 [2] 61 91 [2] 7d be }

  condition:
    any of them
}