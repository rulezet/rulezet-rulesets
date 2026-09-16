rule TTP_XOR_QUAD_CurrentVersionRun_9ce3 {
  strings:
    $key_9ce3 = { cf 8c [2] eb 82 [2] c0 ae [2] ee 8c [2] fa 97 [2] f5 8d [2] eb 90 [2] e9 91 [2] f2 97 [2] ee 90 [2] f2 bf }

  condition:
    any of them
}