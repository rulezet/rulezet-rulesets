rule infostealer_xor_patterns {
  meta:
    author      = "jeFF0Falltrades"
    hash        = "d5d1d28270adc1588cf6be33a876587a3c689f6a51ea797eae6b64b5b15805b1"
    description = "The XOR and string patterns shown here appear to be unique to certain information-stealing malware families, namely LokiBot and Pony/Fareit. The XOR patterns were observed in a several loaders and payloads for LokiBot, but have also appeared (less frequently) in Pony/Fareit loaders and samples. The two accompanying rules below can be used to further classify the final payloads."

  strings:
            $hx_get_input = { ff 15 58 7f 47 00 a1 60 7f 47 00 2b c7 3d 43 01 00 00 }

            $hx_xor_1 = { 80 31 45 FF 45 FC 81 7D FC 07 5E 00 00 }

            $hx_xor_2 = { c8 51 44 c6 a7 4a cf 51 7f 75 55 05 }

            $hx_xor_3 = { 8d 14 01 83 e2 0f 8a 14 3a 30 10 40 }

            $hx_xor_4 = { 81 F1 54 AD 58 43 D1 E9 48 }

  condition:
    $hx_xor_4 or 2 of them
}