rule TTP_XOR_QUAD_CurrentVersionRun_03e2 {
  strings:
    $key_03e2 = { 50 8d [2] 74 83 [2] 5f af [2] 71 8d [2] 65 96 [2] 6a 8c [2] 74 91 [2] 76 90 [2] 6d 96 [2] 71 91 [2] 6d be }

  condition:
    any of them
}