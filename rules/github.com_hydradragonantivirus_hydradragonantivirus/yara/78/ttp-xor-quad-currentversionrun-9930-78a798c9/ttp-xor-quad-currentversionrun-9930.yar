rule TTP_XOR_QUAD_CurrentVersionRun_9930 {
  strings:
    $key_9930 = { ca 5f [2] ee 51 [2] c5 7d [2] eb 5f [2] ff 44 [2] f0 5e [2] ee 43 [2] ec 42 [2] f7 44 [2] eb 43 [2] f7 6c }

  condition:
    any of them
}