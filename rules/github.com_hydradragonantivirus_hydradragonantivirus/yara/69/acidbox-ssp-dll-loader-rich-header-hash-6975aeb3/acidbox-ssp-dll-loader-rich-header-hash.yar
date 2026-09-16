import "pe"
import "hash"
rule AcidBox_SSP_DLL_Loader_Rich_Header_Hash {
  meta:
    description = "Detects AcidBox SSP DLL loaders, based on a unique rich header hash"
    author      = "BitsOfBinary"
    reference   = "https://unit42.paloaltonetworks.com/acidbox-rare-malware/"
    reference   = "https://bitsofbinary.github.io/yara/2023/03/23/100daysofyara-day-82.html"
    hash        = "003669761229d3e1db0f5a5b333ef62b3dffcc8e27c821ce9018362e0a2df7e9"
    version     = "1.0"
    date        = "2023-03-23"
    DaysofYARA  = "82/100"

  condition:
    hash.md5(pe.rich_signature.clear_data) == "269af2751efee65b1ab00622816c83e6"
}