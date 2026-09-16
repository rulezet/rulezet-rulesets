rule TTP_XOR_WriteProcessMemory_9daf {
  strings:
    $key_9daf = { ca dd [2] f8 ff [2] fe ca [2] d0 ca [2] ef d6 }

  condition:
    any of them
}