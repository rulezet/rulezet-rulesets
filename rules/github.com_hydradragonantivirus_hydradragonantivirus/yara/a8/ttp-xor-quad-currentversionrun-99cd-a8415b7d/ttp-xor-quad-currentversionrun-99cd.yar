rule TTP_XOR_QUAD_CurrentVersionRun_99cd {
  strings:
    $key_99cd = { ca a2 [2] ee ac [2] c5 80 [2] eb a2 [2] ff b9 [2] f0 a3 [2] ee be [2] ec bf [2] f7 b9 [2] eb be [2] f7 91 }

  condition:
    any of them
}