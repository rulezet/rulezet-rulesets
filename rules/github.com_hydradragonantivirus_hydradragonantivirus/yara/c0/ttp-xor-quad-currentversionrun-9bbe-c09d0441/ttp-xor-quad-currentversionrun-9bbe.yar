rule TTP_XOR_QUAD_CurrentVersionRun_9bbe {
  strings:
    $key_9bbe = { c8 d1 [2] ec df [2] c7 f3 [2] e9 d1 [2] fd ca [2] f2 d0 [2] ec cd [2] ee cc [2] f5 ca [2] e9 cd [2] f5 e2 }

  condition:
    any of them
}