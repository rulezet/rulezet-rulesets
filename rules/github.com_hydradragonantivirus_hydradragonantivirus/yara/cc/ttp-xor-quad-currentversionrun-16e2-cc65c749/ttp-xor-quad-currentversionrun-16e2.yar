rule TTP_XOR_QUAD_CurrentVersionRun_16e2 {
  strings:
    $key_16e2 = { 45 8d [2] 61 83 [2] 4a af [2] 64 8d [2] 70 96 [2] 7f 8c [2] 61 91 [2] 63 90 [2] 78 96 [2] 64 91 [2] 78 be }

  condition:
    any of them
}