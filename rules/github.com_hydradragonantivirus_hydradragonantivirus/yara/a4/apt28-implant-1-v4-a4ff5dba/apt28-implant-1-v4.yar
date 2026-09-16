rule APT28_IMPLANT_1_v4
{
meta:
      author = "US-CERT"
      description = "X-AGENT/CHOPSTICK"
      reference = "https://www.us-cert.gov/sites/default/files/publications/AR-17-20045_Enhanced_Analysis_of_GRIZZLY_STEPPE_Activity.pdf"
 strings:
      $XOR_LOOP = { 8B 45 FC 8D 0C 06 33 D2 6A 0B 8B C6 5B F7 F3 8A 82 ?? ?? ?? ?? 32 04 0F 46 88 01 3B 75 0C 7C E0 }
 condition:
      (uint16(0) == 0x5A4D) and all of them
}