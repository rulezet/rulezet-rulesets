rule _ASPack_v2xx_
{
	meta:
		description = "ASPack v2.xx"
	strings:
		$0 = {60 E8 70 05 ?? ?? EB}
		$1 = {60 ?? ??}
	condition:
		$0 at entrypoint or $1 at entrypoint
}