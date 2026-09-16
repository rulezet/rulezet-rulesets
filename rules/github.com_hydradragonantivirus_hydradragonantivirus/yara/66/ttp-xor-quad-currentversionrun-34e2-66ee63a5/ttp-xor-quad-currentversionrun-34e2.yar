rule TTP_XOR_QUAD_CurrentVersionRun_34e2 {
  strings:
    $key_34e2 = { 67 8d [2] 43 83 [2] 68 af [2] 46 8d [2] 52 96 [2] 5d 8c [2] 43 91 [2] 41 90 [2] 5a 96 [2] 46 91 [2] 5a be }

  condition:
    any of them
}