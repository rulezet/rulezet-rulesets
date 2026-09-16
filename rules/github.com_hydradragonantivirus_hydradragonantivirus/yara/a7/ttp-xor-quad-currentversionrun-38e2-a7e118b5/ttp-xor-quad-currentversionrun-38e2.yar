rule TTP_XOR_QUAD_CurrentVersionRun_38e2 {
  strings:
    $key_38e2 = { 6b 8d [2] 4f 83 [2] 64 af [2] 4a 8d [2] 5e 96 [2] 51 8c [2] 4f 91 [2] 4d 90 [2] 56 96 [2] 4a 91 [2] 56 be }

  condition:
    any of them
}