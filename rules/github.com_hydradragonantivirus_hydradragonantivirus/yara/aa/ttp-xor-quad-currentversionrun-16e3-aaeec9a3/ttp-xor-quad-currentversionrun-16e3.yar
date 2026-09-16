rule TTP_XOR_QUAD_CurrentVersionRun_16e3 {
  strings:
    $key_16e3 = { 45 8c [2] 61 82 [2] 4a ae [2] 64 8c [2] 70 97 [2] 7f 8d [2] 61 90 [2] 63 91 [2] 78 97 [2] 64 90 [2] 78 bf }

  condition:
    any of them
}